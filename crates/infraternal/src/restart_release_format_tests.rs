//! Proves `restart --binary` admits exactly what the release pipeline signs, #211 S1 [184,224,226].
//!
//! Each test lays out a release bundle with the file set `scripts/release/build` produces
//! and has the real signer Worker code (`apps/release-signer`) sign it through
//! `scripts/release/worker-sign-fixture.ts` with a throwaway key. Admission then runs
//! with that key as the only trusted signer; the built-in D224 keys never sign anything here.

use super::fixture::Directory;
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

/// The edge version every bundle in these tests carries.
const VERSION: &str = "edge-20261114T000000Z";

/// The repository root, where the release scripts and license notices live.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A pipeline-shaped bundle in a fresh trusted directory, before signing.
struct Bundle {
    /// Keeps the private directory alive for the test.
    _directory: Directory,
    /// The bundle directory; the replacement image sits directly inside it.
    root: PathBuf,
}
impl Bundle {
    /// Lays out the files `scripts/release/build` puts in a bundle. This platform's artifact
    /// holds `image`; the other images and manifests hold placeholder bytes, and the license
    /// notices are the repository's own, because the signer refuses a release without them.
    fn new(image: &[u8]) -> Self {
        let directory = Directory::new();
        let root = directory.0.join("bundle");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(root.join("VERSION"), format!("{VERSION}\n")).unwrap();
        for name in [
            "infraternal",
            "infraternal-x86_64-musl",
            "infraternal-aarch64-musl",
            "infraternal-x86_64-session-musl",
            "infraternal-aarch64-session-musl",
            "proxy-traefik-darwin-amd64.json",
            "proxy-traefik-darwin-arm64.json",
            "proxy-traefik-linux-amd64.json",
            "proxy-traefik-linux-arm64.json",
        ] {
            std::fs::write(root.join(name), format!("placeholder {name}\n")).unwrap();
        }
        crate::test_executable::write(&root.join(artifact_name()), image, 0o700);
        let notices = root.join("licenses/libghostty-vt");
        std::fs::create_dir_all(&notices).unwrap();
        for entry in std::fs::read_dir(repo().join("licenses/libghostty-vt")).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), notices.join(entry.file_name())).unwrap();
        }
        Self {
            _directory: directory,
            root,
        }
    }

    /// Signs the bundle with the signer Worker; returns the line that trusts its throwaway key.
    fn sign(&self) -> String {
        let output = Command::new("bun")
            .arg(repo().join("scripts/release/worker-sign-fixture.ts"))
            .arg(&self.root)
            .arg(VERSION)
            .output()
            .expect("bun runs the release signer Worker (it is in the dev shell)");
        assert!(
            output.status.success(),
            "the signer Worker refused the bundle: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    /// The replacement image `restart --binary` is pointed at.
    fn image(&self) -> PathBuf {
        self.root.join(artifact_name())
    }
}

/// Runs the real admission path (sealed copy, metadata checks, image probe) with `trust`.
fn admit(path: PathBuf, trust: &str) -> io::Result<Opened> {
    Opened::open_with(path, |file, path| {
        verify_metadata(file, path, |version, image, name, sums, signature| {
            infraternal_server::release_verify::verify_identity_with_trust(
                version, image, name, sums, signature, trust,
            )
        })
    })
}

/// A small executable image that passes the admission probe on this platform.
fn image_bytes() -> Vec<u8> {
    std::fs::read(crate::restart_binary::fixture::stripped_test_image(
        &std::env::current_exe().unwrap(),
    ))
    .unwrap()
}

/// The red/green proof for S1: a release signed the way the pipeline signs it is admitted.
/// Before #211 S1 admission looked for `MANIFEST`, which the pipeline never produces.
#[test]
fn pipeline_signed_release_is_admitted() {
    let bundle = Bundle::new(&image_bytes());
    let trust = bundle.sign();
    // The same bytes also pass the OpenSSH check `scripts/release/verify` runs.
    let signers = bundle.root.join("allowed_signers.test");
    std::fs::write(&signers, &trust).unwrap();
    let sums = std::fs::File::open(bundle.root.join("SHA256SUMS")).unwrap();
    let checked = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&signers)
        .args([
            "-I",
            "release@infraternal.com",
            "-n",
            "infraternal-release",
            "-s",
        ])
        .arg(bundle.root.join("SHA256SUMS.sig"))
        .stdin(sums)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "ssh-keygen refused the Worker signature"
    );
    let sums = std::fs::read_to_string(bundle.root.join("SHA256SUMS")).unwrap();
    assert!(
        sums.lines()
            .any(|line| line.ends_with("  licenses/libghostty-vt/README.md")),
        "the fixture must carry the nested notice names real releases sign"
    );
    let admitted = admit(bundle.image(), &trust);
    assert!(
        admitted.is_ok(),
        "a pipeline-signed release must be admitted: {:?}",
        admitted.err()
    );
}

/// Small bytes for refusal tests: verification runs before the executable probe, so a
/// refusal here is always a metadata refusal (`PermissionDenied` or `NotFound`).
const CANDIDATE: &[u8] = b"candidate image bytes\n";

/// Asserts admission fails with `kind`, which tells a metadata refusal from a probe failure.
fn refused(path: PathBuf, trust: &str, kind: io::ErrorKind, case: &str) {
    match admit(path, trust) {
        Ok(_) => panic!("{case}: admitted"),
        Err(error) => assert_eq!(error.kind(), kind, "{case}"),
    }
}

/// Changing the image after signing, or swapping in another artifact's bytes, is refused.
#[test]
fn tampered_image_is_refused() {
    let bundle = Bundle::new(CANDIDATE);
    let trust = bundle.sign();
    let mut changed = CANDIDATE.to_vec();
    changed[0] ^= 1;
    crate::test_executable::write(&bundle.image(), &changed, 0o700);
    refused(
        bundle.image(),
        &trust,
        io::ErrorKind::PermissionDenied,
        "flipped byte",
    );
    let other = std::fs::read(bundle.root.join("infraternal-x86_64-session-musl")).unwrap();
    crate::test_executable::write(&bundle.image(), &other, 0o700);
    refused(
        bundle.image(),
        &trust,
        io::ErrorKind::PermissionDenied,
        "another signed artifact",
    );
}

/// A signature by any key but a trusted one is refused, and so is the throwaway key under
/// the compiled-in D224 trust: `Opened::open` is the production admission path.
#[test]
fn wrong_key_is_refused() {
    let bundle = Bundle::new(CANDIDATE);
    bundle.sign();
    let other = Bundle::new(CANDIDATE).sign();
    refused(
        bundle.image(),
        &other,
        io::ErrorKind::PermissionDenied,
        "other throwaway key",
    );
    let error = Opened::open(bundle.image())
        .err()
        .expect("production trust admitted a test key");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

/// Without `SHA256SUMS.sig`, or with an empty or truncated one, nothing is admitted.
#[test]
fn missing_signature_is_refused() {
    let bundle = Bundle::new(CANDIDATE);
    let trust = bundle.sign();
    let signature = bundle.root.join("SHA256SUMS.sig");
    let armor = std::fs::read(&signature).unwrap();
    std::fs::write(&signature, &armor[..armor.len() / 2]).unwrap();
    refused(
        bundle.image(),
        &trust,
        io::ErrorKind::PermissionDenied,
        "truncated signature",
    );
    std::fs::write(&signature, b"").unwrap();
    refused(
        bundle.image(),
        &trust,
        io::ErrorKind::PermissionDenied,
        "empty signature",
    );
    std::fs::remove_file(&signature).unwrap();
    refused(
        bundle.image(),
        &trust,
        io::ErrorKind::NotFound,
        "no signature",
    );
}

/// Extra or missing files and list entries are refused: an unsigned extra line, a list
/// without the image or without `VERSION`, a missing or changed `VERSION`, and a legacy
/// `MANIFEST` pair on its own. The signer Worker signs whatever the bucket holds, so the
/// unsigned-entry cases are signed by it and still refused.
#[test]
fn extra_or_missing_files_are_refused() {
    // An extra line appended after signing breaks the signature.
    let bundle = Bundle::new(CANDIDATE);
    let trust = bundle.sign();
    let sums = bundle.root.join("SHA256SUMS");
    let mut listed = std::fs::read(&sums).unwrap();
    listed.extend_from_slice(format!("{}  extra-file\n", "0".repeat(64)).as_bytes());
    std::fs::write(&sums, &listed).unwrap();
    refused(
        bundle.image(),
        &trust,
        io::ErrorKind::PermissionDenied,
        "unsigned extra line",
    );

    // A missing VERSION file, then a VERSION that differs from the signed one.
    let bundle = Bundle::new(CANDIDATE);
    let trust = bundle.sign();
    std::fs::remove_file(bundle.root.join("VERSION")).unwrap();
    refused(
        bundle.image(),
        &trust,
        io::ErrorKind::NotFound,
        "VERSION file missing",
    );
    std::fs::write(bundle.root.join("VERSION"), "edge-20261115T000000Z\n").unwrap();
    refused(
        bundle.image(),
        &trust,
        io::ErrorKind::PermissionDenied,
        "VERSION changed",
    );

    // The image was not in the release when it was signed.
    let bundle = Bundle::new(CANDIDATE);
    let bytes = std::fs::read(bundle.image()).unwrap();
    std::fs::remove_file(bundle.image()).unwrap();
    let trust = bundle.sign();
    crate::test_executable::write(&bundle.image(), &bytes, 0o700);
    refused(
        bundle.image(),
        &trust,
        io::ErrorKind::PermissionDenied,
        "image not listed",
    );

    // VERSION was not in the release when it was signed.
    let bundle = Bundle::new(CANDIDATE);
    std::fs::remove_file(bundle.root.join("VERSION")).unwrap();
    let trust = bundle.sign();
    std::fs::write(bundle.root.join("VERSION"), format!("{VERSION}\n")).unwrap();
    refused(
        bundle.image(),
        &trust,
        io::ErrorKind::PermissionDenied,
        "VERSION not listed",
    );

    // A signed VERSION that is not exactly one stable or edge version and a newline.
    for declared in ["../edge\n", "edge-20261114T000000Z", "1.2.3\n\n", "1.2\n"] {
        let bundle = Bundle::new(CANDIDATE);
        std::fs::write(bundle.root.join("VERSION"), declared).unwrap();
        let trust = bundle.sign();
        refused(
            bundle.image(),
            &trust,
            io::ErrorKind::PermissionDenied,
            &format!("signed VERSION {declared:?}"),
        );
    }

    // Only the retired MANIFEST pair: there is one signed format.
    let bundle = Bundle::new(CANDIDATE);
    let trust = bundle.sign();
    for (from, to) in [
        ("SHA256SUMS", "MANIFEST"),
        ("SHA256SUMS.sig", "MANIFEST.sig"),
    ] {
        std::fs::rename(bundle.root.join(from), bundle.root.join(to)).unwrap();
    }
    refused(
        bundle.image(),
        &trust,
        io::ErrorKind::NotFound,
        "legacy MANIFEST only",
    );
}

/// An auto-update switches from the file the updater verified, never from the path
/// (#211 S4, J734 P3-b). Swapping other bytes onto the path after verification changes
/// nothing: the sealed copy holds the verified bytes and its signature still checks,
/// while a path admission of the swapped file is refused.
#[test]
fn an_update_switch_runs_the_verified_file_even_if_the_path_is_swapped() {
    use std::os::unix::fs::FileExt;
    let original = image_bytes();
    let bundle = Bundle::new(&original);
    let trust = bundle.sign();
    let verified = std::fs::File::open(bundle.image()).unwrap();
    let swapped = bundle.root.join("swapped");
    let mut other = original.clone();
    *other.last_mut().unwrap() ^= 0xff;
    crate::test_executable::write(&swapped, &other, 0o700);
    std::fs::rename(&swapped, bundle.image()).unwrap();
    let admitted = Opened::from_file(verified, bundle.image(), |file, path| {
        verify_metadata(file, path, |version, image, name, sums, signature| {
            infraternal_server::release_verify::verify_identity_with_trust(
                version, image, name, sums, signature, &trust,
            )
        })
    })
    .expect("the verified file is admitted");
    let mut sealed = vec![0; original.len()];
    admitted.image.file.read_exact_at(&mut sealed, 0).unwrap();
    assert_eq!(sealed, original, "the sealed copy holds the verified bytes");
    assert_eq!(admitted.path, bundle.image());
    assert!(
        admit(bundle.image(), &trust).is_err(),
        "reopening the path would have found other bytes"
    );
}
