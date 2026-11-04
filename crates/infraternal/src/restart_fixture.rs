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
