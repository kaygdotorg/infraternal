//! Unit checks for installing a signed release folder by hand (#211 S6).
//!
//! A stand-in verifier checks each payload's SHA-256 against the folder's `SHA256SUMS` and
//! reads the version from `VERSION`; the real signature check is the server's
//! `release_verify`, which `restart --binary` and the updater already prove.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use std::fmt::Write as _;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

/// The image name used by these tests.
const IMAGE: &str = "infraternal-x86_64-musl";
/// The signed version of every test release.
const VERSION: &str = "edge-20261122T010203Z";

/// A fresh private scratch folder, removed on drop.
struct Scratch(PathBuf);
impl Scratch {
    /// Create a fresh private folder tagged `tag`.
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "release-adopt-{tag}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The stand-in verifier: `name` must be listed in `sums` with this payload's digest.
fn verify(
    version: &File,
    payload: &File,
    name: &str,
    sums: &[u8],
    _: &[u8],
) -> Result<String, &'static str> {
    let digest = crate::apply::digest(payload)?;
    let text = std::str::from_utf8(sums).unwrap();
    if !text.lines().any(|line| line == format!("{digest}  {name}")) {
        return Err("the release does not match its signed checksums");
    }
    let mut signed = String::new();
    version
        .try_clone()
        .unwrap()
        .read_to_string(&mut signed)
        .unwrap();
    Ok(signed.trim_end().to_owned())
}

/// Write a release folder with `image` bytes and, when `web`, a web build holding `page`.
fn release(scratch: &Scratch, name: &str, image: &[u8], web: Option<&[u8]>) -> PathBuf {
    let folder = scratch.0.join(name);
    std::fs::create_dir(&folder).unwrap();
    std::fs::write(folder.join(IMAGE), image).unwrap();
    std::fs::write(folder.join("VERSION"), format!("{VERSION}\n")).unwrap();
    std::fs::write(folder.join("SHA256SUMS.sig"), b"signature").unwrap();
    let mut names = vec!["VERSION", IMAGE];
    if let Some(page) = web {
        let mut builder =
            tar::Builder::new(std::fs::File::create(folder.join(crate::web::ARCHIVE)).unwrap());
        let mut header = tar::Header::new_ustar();
        header.set_size(page.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "index.html", page)
            .unwrap();
        builder.finish().unwrap();
        names.push(crate::web::ARCHIVE);
    }
    let mut sums = String::new();
    for name in &names {
        let digest = crate::apply::digest(&File::open(folder.join(name)).unwrap()).unwrap();
        writeln!(sums, "{digest}  {name}").unwrap();
    }
    std::fs::write(folder.join("SHA256SUMS"), sums).unwrap();
    folder
}

/// A private data folder.
fn data(scratch: &Scratch) -> PathBuf {
    let data = scratch.0.join("data");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&data)
        .unwrap();
    data
}

/// A plan writes nothing; install copies, verifies, unpacks the web build and points `current`; a second run keeps it.
#[test]
fn a_release_folder_installs_with_its_web_build_and_becomes_the_boot_pointer() {
    let scratch = Scratch::new("install");
    let source = release(&scratch, "release", b"image-one", Some(b"<p>one</p>"));
    let data = data(&scratch);
    let before = plan(&data, &source, IMAGE, &verify).unwrap();
    assert_eq!(
        before,
        Plan {
            version: VERSION.into(),
            web: true,
            installed: false,
            current: None
        }
    );
    assert!(!data.join("updates").exists(), "a plan writes nothing");

    let installed = install(&data, &source, IMAGE, &verify).unwrap();
    let folder = data.join("updates/releases").join(VERSION);
    assert_eq!(
        installed,
        Installed {
            version: VERSION.into(),
            image: folder.join(IMAGE),
            web: true,
            kept: false
        }
    );
    assert_eq!(std::fs::read(folder.join(IMAGE)).unwrap(), b"image-one");
    assert_eq!(
        std::fs::metadata(folder.join(IMAGE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::read(folder.join("web/index.html")).unwrap(),
        b"<p>one</p>"
    );
    assert_eq!(
        std::fs::read_link(data.join("updates/current")).unwrap(),
        Path::new("releases").join(VERSION)
    );
    // No download folder is left behind.
    let leftovers: Vec<_> = std::fs::read_dir(data.join("updates"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with("download-") || name.starts_with("retired-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    // Running it again keeps the installed folder as it is.
    let again = install(&data, &source, IMAGE, &verify).unwrap();
    assert!(again.kept);
    assert!(plan(&data, &source, IMAGE, &verify).unwrap().installed);
}

/// An installed version is never replaced by different bytes.
#[test]
fn the_same_version_with_other_bytes_is_refused() {
    let scratch = Scratch::new("other");
    let data = data(&scratch);
    install(
        &data,
        &release(&scratch, "one", b"image-one", None),
        IMAGE,
        &verify,
    )
    .unwrap();
    let error = install(
        &data,
        &release(&scratch, "two", b"image-two", None),
        IMAGE,
        &verify,
    )
    .unwrap_err();
    assert!(error.contains("different image"), "{error}");
    assert_eq!(
        std::fs::read(data.join("updates/releases").join(VERSION).join(IMAGE)).unwrap(),
        b"image-one"
    );
}

/// Changed, stripped or linked release files install nothing.
#[test]
fn a_release_that_does_not_match_its_list_or_lacks_its_web_build_is_refused() {
    let scratch = Scratch::new("bad");
    let data = data(&scratch);
    let changed = release(&scratch, "changed", b"image-one", None);
    std::fs::write(changed.join(IMAGE), b"swapped").unwrap();
    assert!(install(&data, &changed, IMAGE, &verify).is_err());
    let stripped = release(&scratch, "stripped", b"image-one", Some(b"<p>one</p>"));
    std::fs::remove_file(stripped.join(crate::web::ARCHIVE)).unwrap();
    assert!(install(&data, &stripped, IMAGE, &verify).is_err());
    assert!(plan(&data, &stripped, IMAGE, &verify).is_err());
    let linked = release(&scratch, "linked", b"image-one", None);
    std::fs::remove_file(linked.join(IMAGE)).unwrap();
    std::os::unix::fs::symlink(changed.join(IMAGE), linked.join(IMAGE)).unwrap();
    assert!(
        install(&data, &linked, IMAGE, &verify).is_err(),
        "a linked image is refused"
    );
    assert!(!data.join("updates/releases").join(VERSION).exists());
    assert!(!data.join("updates/current").exists());
}

/// A pending switch blocks the install.
#[test]
fn nothing_is_installed_while_a_switch_is_in_flight() {
    let scratch = Scratch::new("flight");
    let data = data(&scratch);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(data.join("updates"))
        .unwrap();
    std::fs::write(data.join("updates").join(crate::apply::PENDING), b"{}").unwrap();
    let error = install(
        &data,
        &release(&scratch, "one", b"image-one", None),
        IMAGE,
        &verify,
    )
    .unwrap_err();
    assert!(error.contains("has not finished"), "{error}");
    assert!(!data.join("updates/current").exists());
}
