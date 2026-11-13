//! Makes signed replacement fixtures with an ephemeral in-memory signing key; secrets never enter fixture files [224,226], #157.
use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
    time::Duration,
};
#[path = "../../infraternal-server/tests/support/release_signing.rs"]
mod signing;

/// Keep executable fixtures beneath the effective user's private home root.
/// Build-artifact ancestors may be group writable; restart admission must keep
/// refusing those paths even when their final cache directory is private (#509).
fn image_root() -> PathBuf {
    use std::os::unix::fs::DirBuilderExt;
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
    parent
}

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
        let images = nix::unistd::mkdtemp(&image_root().join("r-XXXXXX")).unwrap();
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

/// Both private roots disappear after successful tests and after assertion failures.
#[test]
fn directory_removes_roots_on_drop_and_unwind() {
    for unwind in [false, true] {
        let directory = Directory::new();
        let images = directory.0.clone();
        let sockets = directory.state().to_owned();
        std::fs::write(images.join("image"), b"fixture").unwrap();
        std::fs::write(sockets.join("state"), b"fixture").unwrap();
        let result = std::panic::catch_unwind(move || {
            let _directory = directory;
            assert!(!unwind, "fixture panic");
        });
        assert_eq!(result.is_err(), unwind);
        assert!(!images.exists());
        assert!(!sockets.exists());
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
            // sleep: poll owned child exit without spinning while its hang guard is active.
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
        // Tests exec this file while sibling tests fork; see `test_executable`.
        crate::test_executable::write(&path, bytes, 0o700);
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
    /// Makes a fixture out of the running test executable, using the cached
    /// stripped copy so the image stays small (see [`stripped_test_image`]).
    pub fn image(path: PathBuf) -> Self {
        let source = stripped_test_image(&std::env::current_exe().unwrap());
        let bytes = std::fs::read(source).unwrap();
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
/// Returns a cached, fully stripped copy of the test executable `source`.
///
/// Debug test images are about 500 MB. Restart code copies the running image
/// into memory on every open and recovery, and on a busy gate disk that copy
/// alone outlasted the 60 s hang bounds (#355). Restart children and signed
/// fixtures therefore run from this copy (about 60 MB). It is made once per
/// build of the test executable and shared; each test still signs its own
/// private copy. A `source` that already is a stripped image is returned as is.
/// The cache uses the same trusted home ancestry as signed fixtures, so a
/// group-writable build directory cannot turn a valid self-reload into refusal.
/// Last-use timestamps include already stripped child images. Lookup, publication,
/// renewal and pruning share a short directory lock across test processes.
pub(crate) fn stripped_test_image(source: &Path) -> PathBuf {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    /// Serializes building the cached image within this test process.
    static BUILDING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let cache = image_root().join("stripped");
    if source
        .file_name()
        .is_some_and(|name| name.to_string_lossy().ends_with(".all-stripped"))
    {
        if source.parent() == Some(cache.as_path()) {
            let cache_lock = lock_stripped_cache(&cache);
            File::open(source)
                .unwrap()
                .set_modified(std::time::SystemTime::now())
                .unwrap();
            cache_lock.unlock().unwrap();
        }
        return source.to_owned();
    }
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
    // Single flight: tests start in parallel on a cold cache, and each used to
    // copy and strip the ~500 MB debug image on its own. About eight
    // concurrent 0.5 GB copy+strip passes starved the disk until even small
    // strips passed their hang guard (#355). One caller per test process
    // builds the image; the others wait here and reuse it.
    let _building = BUILDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cache_lock = lock_stripped_cache(&cache);
    if !image.exists() {
        // Large copies and strip processes must not queue unrelated builds behind this lock.
        cache_lock.unlock().unwrap();
        let mut staging_name = image_name;
        staging_name.push(format!(".{}", uuid::Uuid::new_v4().simple()));
        let staging = cache.join(staging_name);
        crate::test_executable::copy(source, &staging, 0o700);
        strip_all(&staging);
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();
        cache_lock.lock().unwrap();
        match std::fs::hard_link(&staging, &image) {
            Ok(()) => std::fs::remove_file(&staging).unwrap(),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                std::fs::remove_file(&staging).unwrap();
            }
            Err(error) => panic!("could not retain the stripped test image: {error}"),
        }
        prune_stripped_images(&cache, &image, std::time::SystemTime::now());
    }
    let metadata = std::fs::symlink_metadata(&image).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.mode() & 0o777, 0o700);
    // A read-only descriptor renews grace without an inheritable executable writer.
    File::open(&image)
        .unwrap()
        .set_modified(std::time::SystemTime::now())
        .unwrap();
    cache_lock.unlock().unwrap();
    image
}

/// Lock the stable cache directory inode for lookup, renewal, publication and pruning.
/// Cache maintenance never removes this directory. Callers release the lock before
/// copying or stripping an image, and on return so forked children cannot prolong it.
fn lock_stripped_cache(cache: &Path) -> File {
    let directory = File::open(cache).unwrap();
    directory.lock().unwrap();
    directory
}

/// Keep the three newest completed images, plus the caller's image and a six-hour grace
/// period for concurrent test processes. Sweep only after creating an image, so cache hits
/// stay cheap. Staging copies, symlinks and directories are never eviction candidates.
/// Cleanup is best effort: another process can remove an entry between listing and unlink.
fn prune_stripped_images(cache: &Path, current: &Path, now: std::time::SystemTime) {
    let mut images: Vec<_> = std::fs::read_dir(cache)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.extension()? != "all-stripped" {
                return None;
            }
            let metadata = std::fs::symlink_metadata(&path).ok()?;
            if !metadata.is_file() {
                return None;
            }
            Some((metadata.modified().ok()?, path))
        })
        .collect();
    images.sort_unstable_by(|left, right| right.cmp(left));
    for (modified, path) in images.into_iter().skip(3) {
        if path != current
            && now
                .duration_since(modified)
                .is_ok_and(|age| age > Duration::from_hours(6))
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Pruning bounds old builds without touching recent concurrent users or unfinished copies.
#[test]
fn stripped_cache_prunes_only_stale_completed_images() {
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};
    let directory = Directory::new();
    let cache = &directory.0;
    let now = UNIX_EPOCH + Duration::from_secs(100_000);
    let mut images = Vec::new();
    for index in 0..7 {
        let path = cache.join(format!("{index}.all-stripped"));
        let file = File::create(&path).unwrap();
        file.set_modified(now - Duration::from_secs(30_000 - index * 1_000))
            .unwrap();
        images.push(path);
    }
    let recent = cache.join("recent.all-stripped");
    let file = File::create(&recent).unwrap();
    file.set_modified(now - Duration::from_secs(6 * 60 * 60 - 1))
        .unwrap();
    let future = cache.join("future.all-stripped");
    File::create(&future)
        .unwrap()
        .set_modified(now + Duration::from_secs(1))
        .unwrap();
    let staging = cache.join("copy.all-stripped.staging");
    File::create(&staging)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH)
        .unwrap();
    let link = cache.join("link.all-stripped");
    symlink(&images[1], &link).unwrap();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| {
                barrier.wait();
                prune_stripped_images(cache, &images[0], now);
            });
        }
    });
    assert!(images[0].exists(), "the caller's image must survive");
    for image in &images[1..6] {
        assert!(!image.exists(), "stale image retained: {}", image.display());
    }
    assert!(images[6].exists(), "keep the three newest completed images");
    assert!(recent.exists());
    assert!(future.exists());
    assert!(staging.exists());
    assert!(std::fs::symlink_metadata(link).unwrap().is_symlink());
    // More recent images than the count limit must all survive, including the age boundary.
    let mut active = Vec::new();
    for index in 0..5 {
        let path = cache.join(format!("active-{index}.all-stripped"));
        File::create(&path)
            .unwrap()
            .set_modified(now - Duration::from_secs(6 * 60 * 60 - index))
            .unwrap();
        active.push(path);
    }
    prune_stripped_images(cache, &images[0], now);
    assert!(active.iter().all(|path| path.exists()));
}

/// Reusing an old build renews its eviction grace; a tiny system ELF keeps this test cheap.
#[cfg(target_os = "linux")]
#[test]
fn stripped_cache_reuse_renews_grace() {
    use std::time::UNIX_EPOCH;
    let directory = Directory::new();
    let source = directory
        .0
        .join(format!("cache-hit-{}", uuid::Uuid::new_v4().simple()));
    crate::test_executable::copy(Path::new("/bin/true"), &source, 0o700);
    let image = stripped_test_image(&source);
    let mut renewed = true;
    for current in [&source, &image] {
        File::open(&image)
            .unwrap()
            .set_modified(UNIX_EPOCH)
            .unwrap();
        assert_eq!(stripped_test_image(current), image);
        renewed &= std::fs::metadata(&image).unwrap().modified().unwrap() > UNIX_EPOCH;
    }
    std::fs::remove_file(image).unwrap();
    assert!(
        renewed,
        "reusing an old image must renew its eviction grace"
    );
}

/// Removes all symbols and debug sections from the image at `path`, in place.
/// `strip` runs as its own single-threaded process in its own process group,
/// which owns every writer. Its run is bounded by [`RESTART_TEST_HANG_BOUND`]
/// as a hang guard only: a stuck `strip` kills its group and fails the test
/// instead of blocking it forever (J223 on #355).
pub(crate) fn strip_all(path: &Path) {
    use std::os::unix::process::CommandExt;
    let mut child = std::process::Command::new("strip")
        .arg("--strip-all")
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + RESTART_TEST_HANG_BOUND;
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            let group = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
            let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
            let _ = child.wait();
            panic!(
                "strip {} exceeded {RESTART_TEST_HANG_BOUND:?}",
                path.display()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "strip {} failed: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
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
