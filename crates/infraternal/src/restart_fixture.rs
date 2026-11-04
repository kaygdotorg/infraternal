//! Makes signed replacement fixtures with an ephemeral in-memory signing key; secrets never enter fixture files [224,226], #157.
use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
    time::Duration,
};
#[path = "../../infraternal-server/tests/support/release_signing.rs"]
mod signing;

/// Private roots for executable admission and short Unix sockets, owned by one test.
/// Executables stay under the effective user's real home even when the gate puts state in /tmp.
pub(crate) struct Directory(
    /// Trusted executable ancestry; each test gets a fresh directory.
    pub(crate) PathBuf,
    /// Independent socket state, short enough for Unix socket address limits.
    PathBuf,
);

impl Directory {
    /// Allocate unique private roots without relying on shared state or the invoking user's HOME.
    pub(crate) fn new() -> Self {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let home = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
            .unwrap()
            .expect("test account has a home directory")
            .dir;
        let parent = home.join(".cache/infraternal-restart-tests");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&parent)
            .unwrap();
        let images = nix::unistd::mkdtemp(&parent.join("r-XXXXXX")).unwrap();
        let mut directory = Self(images, PathBuf::new());
        let requested = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").map(PathBuf::from);
        let sockets = if let Some(root) = requested.filter(|root| {
            root.join("r-XXXXXX/restart/control.sock")
                .as_os_str()
                .as_encoded_bytes()
                .len()
                <= 107
        }) {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&root)
                .unwrap();
            nix::unistd::mkdtemp(&root.join("r-XXXXXX")).unwrap()
        } else {
            nix::unistd::mkdtemp("/tmp/ir-XXXXXX").unwrap()
        };
        directory.1 = sockets;
        // Cargo images can inherit a group-writable umask; this job owns its test image.
        std::fs::set_permissions(
            std::env::current_exe().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        directory
    }

    /// Return socket state independently of the trusted replacement executable root.
    pub(crate) fn state(&self) -> &Path {
        &self.1
    }
}

impl Drop for Directory {
    /// Remove only this test's private directories on success or unwinding.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Own a child launched with `process_group(0)` until its output is collected.
/// Drop kills that private group and reaps the leader, including on test panic.
pub(crate) struct ChildGuard(Option<std::process::Child>);
impl ChildGuard {
    /// Take ownership immediately after spawning a child in its own process group.
    pub(crate) fn new(child: std::process::Child) -> Self {
        Self(Some(child))
    }
    /// Inspect or signal the owned child without giving up cleanup on panic.
    pub(crate) fn process(&mut self) -> &mut std::process::Child {
        self.0.as_mut().unwrap()
    }
    /// Collect an exited child's pipes and release cleanup ownership.
    pub(crate) fn output(mut self) -> std::process::Output {
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}
impl Drop for ChildGuard {
    /// Stop the private process group before reaping its leader.
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let group = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
            let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The guard must reap its leader and stop descendants on ordinary drop and panic.
#[cfg(target_os = "linux")]
#[test]
fn child_guard_stops_its_process_group_on_drop_and_unwind() {
    use std::io::BufRead;
    use std::os::unix::process::CommandExt;
    for unwind in [false, true] {
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 120 & echo $!; wait"])
            .stdout(std::process::Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let leader = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
        let mut descendant = String::new();
        let mut guard = ChildGuard::new(child);
        std::io::BufReader::new(guard.process().stdout.take().unwrap())
            .read_line(&mut descendant)
            .unwrap();
        let descendant: u32 = descendant.trim().parse().unwrap();
        let result = std::panic::catch_unwind(move || {
            let _guard = guard;
            assert!(!unwind, "fixture panic");
        });
        assert_eq!(result.is_err(), unwind);
        assert_eq!(
            nix::sys::signal::kill(leader, None),
            Err(nix::errno::Errno::ESRCH)
        );
        let deadline = std::time::Instant::now() + RESTART_TEST_HANG_BOUND;
        loop {
            let status = std::fs::read_to_string(format!("/proc/{descendant}/stat"));
            if status
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
                || status.as_ref().is_ok_and(|status| {
                    status
                        .rsplit_once(") ")
                        .is_some_and(|(_, tail)| tail.starts_with('Z'))
                })
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "fixture descendant survived cleanup"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Positive test waits use this only as a hang limit; observed events end waits immediately.
pub(crate) const RESTART_TEST_HANG_BOUND: Duration = Duration::from_secs(60);

/// Scratch directory for restart tests, located the way cargo itself does: beside
/// the running test executable (`<target>/<profile>/deps`). Reading `CARGO_TARGET_DIR`
/// instead fails whenever the gate runs with the default target directory or from a
/// harness that does not export it, and it points elsewhere under `--target-dir`.
pub(crate) fn scratch_root() -> PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .expect("test executable has a directory")
        .to_owned()
}

/// A replacement binary for restart tests, together with a freshly signed release manifest
/// and the throwaway trust file that verifies it.
///
/// The signing key lives only in memory while the fixture is created; the files written next
/// to the binary (`MANIFEST`, `MANIFEST.sig`, `VERSION`, `fixture.trust`) hold no secret.
pub(crate) struct Signed {
    pub path: PathBuf,
    trust: String,
}
impl Signed {
    /// Writes `bytes` to `path` as an executable and signs a manifest for it, in the same
    /// folder. The manifest declares an `edge` release named for this platform's artifact.
    pub fn new(path: PathBuf, bytes: &[u8]) -> Self {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let version = b"edge-20261012T000000Z\n";
        let name = super::artifact_name();
        let manifest = format!(
            "infraternal-release-manifest-v1\nversion edge-20261012T000000Z\nchannel edge\n{}  VERSION\n{}  {name}\n",
            hex(&openssl::sha::sha256(version)),
            hex(&openssl::sha::sha256(bytes))
        );
        let (armor, trust) = signing::sign(manifest.as_bytes());
        let parent = path.parent().unwrap();
        std::fs::write(parent.join("MANIFEST"), manifest).unwrap();
        std::fs::write(parent.join("MANIFEST.sig"), armor).unwrap();
        std::fs::write(parent.join("VERSION"), version).unwrap();
        std::fs::write(parent.join("fixture.trust"), &trust).unwrap();
        Self { path, trust }
    }
    /// Makes a fixture out of the running test executable. If it exceeds the largest image
    /// the restart code accepts, debug info is stripped from the copy first.
    pub fn image(path: PathBuf) -> Self {
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        if std::fs::metadata(&path).unwrap().len() > crate::restart_image::MAX_IMAGE {
            assert!(
                std::process::Command::new("strip")
                    .arg("--strip-debug")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let bytes = std::fs::read(&path).unwrap();
        Self::new(path, &bytes)
    }
    /// Reopens a fixture made earlier: reads the trust file beside `path` instead of signing again.
    pub fn existing(path: PathBuf) -> Self {
        let trust = std::fs::read_to_string(path.parent().unwrap().join("fixture.trust")).unwrap();
        Self { path, trust }
    }
    /// Opens the binary the way the restart code does, checking its manifest and signature
    /// against this fixture's trust file.
    pub fn open(&self) -> io::Result<super::Opened> {
        super::Opened::open_with(self.path.clone(), |file, path| self.verify(file, path))
    }
    /// Re-checks an already open `file` against the manifest next to this fixture's binary.
    pub fn verify_snapshot(&self, file: &File) -> io::Result<()> {
        self.verify(file, &self.path)
    }
    fn verify(&self, file: &File, path: &Path) -> io::Result<()> {
        super::verify_metadata(file, path, |file, name, manifest, signature| {
            infraternal_server::release_manifest::verify_manifest_with_trust(
                file,
                name,
                manifest,
                signature,
                &self.trust,
            )
        })
    }
}
/// Lowercase hexadecimal text of `bytes`, as the manifest format writes digests.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}
