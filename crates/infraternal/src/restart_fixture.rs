//! Makes signed replacement fixtures with an ephemeral in-memory signing key; secrets never enter fixture files [224,226], #157.
use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
    time::Duration,
};
#[path = "../../infraternal-server/tests/support/release_signing.rs"]
mod signing;

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
pub(crate) fn stripped_test_image(source: &Path) -> PathBuf {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
        crate::test_executable::copy(source, &staging, 0o700);
        strip_all(&staging);
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

/// Removes all symbols and debug sections from the image at `path`, in place.
/// `strip` runs as its own single-threaded process, which owns every writer.
pub(crate) fn strip_all(path: &Path) {
    let output = std::process::Command::new("strip")
        .arg("--strip-all")
        .arg(path)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
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
