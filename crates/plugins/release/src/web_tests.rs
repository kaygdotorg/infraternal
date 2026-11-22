//! Unit checks for the release web build: the checksum lookup, strict unpacking and the
//! rule that a release image serves its own web folder (#211 S6).
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

/// A fresh private scratch folder for one test, removed on drop.
struct Scratch(PathBuf);
impl Scratch {
    /// Create a fresh private folder tagged `tag`.
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "release-web-{tag}-{}-{}",
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

/// One raw ustar header for `name`, of `kind`, announcing `size` bytes, with its checksum.
fn header(name: &[u8], kind: tar::EntryType, size: u64, link: &[u8]) -> tar::Header {
    let mut header = tar::Header::new_ustar();
    header.as_old_mut().name[..name.len()].copy_from_slice(name);
    header.as_old_mut().linkname[..link.len()].copy_from_slice(link);
    header.set_entry_type(kind);
    header.set_size(size);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    header
}

/// One archive entry for [`archive`]: name, kind, contents and link target.
type Entry<'a> = (&'a [u8], tar::EntryType, &'a [u8], &'a [u8]);

/// Write an archive from `(name, kind, contents, link)` entries into `path`, with raw
/// headers so names a well-behaved builder refuses (`../x`, `/x`) can be written too.
fn archive(path: &Path, entries: &[Entry<'_>]) -> File {
    let mut bytes = Vec::new();
    for (name, kind, contents, link) in entries {
        bytes.extend_from_slice(header(name, *kind, contents.len() as u64, link).as_bytes());
        bytes.extend_from_slice(contents);
        let pad = (512 - contents.len() % 512) % 512;
        bytes.extend(std::iter::repeat_n(0u8, pad));
    }
    bytes.extend(std::iter::repeat_n(0u8, 1024));
    let mut file = std::fs::File::create(path).unwrap();
    file.write_all(&bytes).unwrap();
    std::fs::File::open(path).unwrap()
}

/// Only an exact `infraternal-web.tar` entry counts as listed.
#[test]
fn the_checksum_list_names_the_archive_only_as_a_whole_name() {
    let hex = "0".repeat(64);
    assert!(listed(
        format!("{hex}  VERSION\n{hex}  infraternal-web.tar\n").as_bytes()
    ));
    assert!(listed(format!("{hex} *infraternal-web.tar\n").as_bytes()));
    assert!(!listed(
        format!("{hex}  VERSION\n{hex}  infraternal-x86_64-musl\n").as_bytes()
    ));
    assert!(!listed(
        format!("{hex}  infraternal-web.tar.old\n").as_bytes()
    ));
    assert!(!listed(
        format!("{hex}  licenses/infraternal-web.tar\n").as_bytes()
    ));
    assert!(!listed(b"short  infraternal-web.tar\n"));
}

/// A good archive unpacks with private modes, folders made on demand.
#[test]
fn a_web_build_unpacks_privately_and_whole() {
    let scratch = Scratch::new("good");
    let file = archive(
        &scratch.0.join("web.tar"),
        &[
            (b"./", tar::EntryType::Directory, b"", b""),
            (
                b"./index.html",
                tar::EntryType::Regular,
                b"<html>proof</html>",
                b"",
            ),
            (b"./index.html.br", tar::EntryType::Regular, b"br", b""),
            // A file before its folder's own entry: the folder is made on demand.
            (
                b"./docs/guide/index.html",
                tar::EntryType::Regular,
                b"guide",
                b"",
            ),
            (b"./docs/", tar::EntryType::Directory, b"", b""),
        ],
    );
    let web = scratch.0.join("web");
    extract(&file, &web).unwrap();
    assert_eq!(
        std::fs::read(web.join("index.html")).unwrap(),
        b"<html>proof</html>"
    );
    assert_eq!(
        std::fs::read(web.join("docs/guide/index.html")).unwrap(),
        b"guide"
    );
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&web), 0o700);
    assert_eq!(mode(&web.join("docs/guide")), 0o700);
    assert_eq!(
        mode(&web.join("index.html")),
        0o600,
        "the archive's 0644 is not kept"
    );
}

/// Climbing, absolute and odd names are refused and write nothing outside.
#[test]
fn names_that_climb_or_are_absolute_are_refused() {
    for name in [
        &b"../escape"[..],
        b"/etc/escape",
        b"docs/../../escape",
        b"a b",
        b"..",
        b"x\\y",
    ] {
        let scratch = Scratch::new("climb");
        let file = archive(
            &scratch.0.join("web.tar"),
            &[(name, tar::EntryType::Regular, b"x", b"")],
        );
        assert!(extract(&file, &scratch.0.join("web")).is_err(), "{name:?}");
        assert!(!scratch.0.join("escape").exists());
    }
}

/// Every entry kind other than a file or a folder is refused.
#[test]
fn links_devices_and_fifos_are_refused() {
    for kind in [
        tar::EntryType::Symlink,
        tar::EntryType::Link,
        tar::EntryType::Char,
        tar::EntryType::Block,
        tar::EntryType::Fifo,
    ] {
        let scratch = Scratch::new("kind");
        let file = archive(
            &scratch.0.join("web.tar"),
            &[(b"link", kind, b"", b"/etc/passwd")],
        );
        assert!(extract(&file, &scratch.0.join("web")).is_err(), "{kind:?}");
        assert!(std::fs::symlink_metadata(scratch.0.join("web/link")).is_err());
    }
}

/// A duplicate name and an existing target folder are refused.
#[test]
fn a_file_cannot_be_written_twice_or_through_a_planted_link() {
    let scratch = Scratch::new("twice");
    let file = archive(
        &scratch.0.join("web.tar"),
        &[
            (b"index.html", tar::EntryType::Regular, b"first", b""),
            (b"index.html", tar::EntryType::Regular, b"second", b""),
        ],
    );
    let web = scratch.0.join("web");
    assert!(extract(&file, &web).is_err());
    assert_eq!(std::fs::read(web.join("index.html")).unwrap(), b"first");
    // The target folder itself must be new: unpacking never merges into an existing one.
    assert!(extract(&file, &web).is_err());
}

/// The entry bound and a truncated entry are refused.
#[test]
fn too_many_entries_and_truncated_archives_are_refused() {
    let scratch = Scratch::new("many");
    let names: Vec<Vec<u8>> = (0..=MAX_ENTRIES)
        .map(|i| format!("f{i}").into_bytes())
        .collect();
    let entries: Vec<_> = names
        .iter()
        .map(|name| (name.as_slice(), tar::EntryType::Regular, &b""[..], &b""[..]))
        .collect();
    let file = archive(&scratch.0.join("web.tar"), &entries);
    assert_eq!(
        extract(&file, &scratch.0.join("web")),
        Err("the release's web build has too many files")
    );
    // A header that announces more bytes than the archive holds.
    let mut truncated = header(b"index.html", tar::EntryType::Regular, 4096, b"")
        .as_bytes()
        .to_vec();
    truncated.extend_from_slice(b"short");
    std::fs::write(scratch.0.join("cut.tar"), &truncated).unwrap();
    let file = std::fs::File::open(scratch.0.join("cut.tar")).unwrap();
    assert!(extract(&file, &scratch.0.join("cut")).is_err());
}

/// Positional reads leave the caller's offset where it was.
#[test]
fn unpacking_leaves_the_callers_file_offset_alone() {
    use std::io::Seek;
    let scratch = Scratch::new("offset");
    let mut file = archive(
        &scratch.0.join("web.tar"),
        &[(b"index.html", tar::EntryType::Regular, b"x", b"")],
    );
    file.seek(io::SeekFrom::Start(7)).unwrap();
    extract(&file, &scratch.0.join("web")).unwrap();
    assert_eq!(file.stream_position().unwrap(), 7);
}

/// A data folder with `updates/releases/<version>/` holding an image, optionally `web/`,
/// and `current` pointing at it.
fn installed(scratch: &Scratch, version: &str, web: bool) -> PathBuf {
    let data = scratch.0.join("data");
    let release = data.join("updates/releases").join(version);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&release)
        .unwrap();
    std::fs::write(release.join("infraternal-x86_64-musl"), b"image").unwrap();
    if web {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(release.join(FOLDER))
            .unwrap();
    }
    let _ = std::fs::remove_file(data.join("updates/current"));
    std::os::unix::fs::symlink(
        Path::new("releases").join(version),
        data.join("updates/current"),
    )
    .unwrap();
    data
}

/// An image in `releases/<v>/` serves its `web/`, also when started through `current`.
#[test]
fn a_release_image_serves_its_own_web_folder_even_through_the_boot_pointer() {
    let scratch = Scratch::new("rule");
    let data = installed(&scratch, "edge-20261122T000000Z", true);
    let release = data.join("updates/releases/edge-20261122T000000Z");
    let real = std::fs::canonicalize(release.join(FOLDER)).unwrap();
    assert_eq!(
        release_web(&release.join("infraternal-x86_64-musl"), &data),
        Some(real.clone())
    );
    // A cold start runs `current/<image>`; the rule resolves it to the release folder now,
    // so a later move of the pointer does not change what this process serves.
    assert_eq!(
        release_web(&data.join("updates/current/infraternal-x86_64-musl"), &data),
        Some(real)
    );
}

/// Fixed paths, relative argv[0], releases without web and other data folders keep `--web-root`.
#[test]
fn other_images_keep_their_web_root_flag() {
    let scratch = Scratch::new("other");
    let data = installed(&scratch, "edge-20261122T000000Z", false);
    // A release without a web build.
    assert_eq!(
        release_web(&data.join("updates/current/infraternal-x86_64-musl"), &data),
        None
    );
    // A fixed install path, like an operator's /opt/infraternal/<build>/infraternal.
    let fixed = scratch.0.join("opt/infraternal");
    std::fs::create_dir_all(fixed.join(FOLDER)).unwrap();
    std::fs::write(fixed.join("infraternal"), b"image").unwrap();
    assert_eq!(release_web(&fixed.join("infraternal"), &data), None);
    // Relative argv[0] (started from PATH), and another server's data folder.
    assert_eq!(release_web(Path::new("infraternal"), &data), None);
    let elsewhere = installed(&Scratch::new("elsewhere"), "edge-20261122T000000Z", true);
    assert_eq!(
        release_web(
            &elsewhere.join("updates/current/infraternal-x86_64-musl"),
            &data
        ),
        None
    );
}

/// Mirroring hard-links files and never copies a link.
#[test]
fn the_previous_web_build_is_mirrored_with_hard_links() {
    use std::os::unix::fs::MetadataExt;
    let scratch = Scratch::new("mirror");
    let from = scratch.0.join("from");
    std::fs::create_dir_all(from.join("docs")).unwrap();
    std::fs::write(from.join("index.html"), b"page").unwrap();
    std::fs::write(from.join("docs/a.html"), b"doc").unwrap();
    std::os::unix::fs::symlink("/etc/passwd", from.join("planted")).unwrap();
    let into = scratch.0.join("into");
    mirror(&from, &into).unwrap();
    assert_eq!(
        std::fs::metadata(into.join("index.html")).unwrap().ino(),
        std::fs::metadata(from.join("index.html")).unwrap().ino()
    );
    assert_eq!(std::fs::read(into.join("docs/a.html")).unwrap(), b"doc");
    assert!(
        std::fs::symlink_metadata(into.join("planted")).is_err(),
        "links are never mirrored"
    );
}

/// Write `bytes` as a private (0600) file, the way the updater keeps release files.
fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

/// The whole web lifecycle of one update A → B and the owner's roll back (#211 S6):
/// installing B unpacks its staged archive into `releases/<B>/web/`, the switch keeps A's
/// web build in `previous/web/`, and a manual roll back after the commit (which removed
/// `releases/<A>/`) brings A's web build back beside its image.
#[test]
fn an_update_installs_its_web_build_and_a_roll_back_brings_the_previous_one_back() {
    use std::os::unix::fs::OpenOptionsExt;
    const IMAGE: &str = "infraternal-test-musl";
    const A: &str = "edge-20261122T000001Z";
    const B: &str = "edge-20261122T000002Z";
    let scratch = Scratch::new("lifecycle");
    let data = scratch.0.join("data");
    let updates = data.join("updates");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(updates.join("releases").join(A).join(FOLDER))
        .unwrap();
    private_file(&updates.join("releases").join(A).join(IMAGE), b"image-a");
    private_file(
        &updates
            .join("releases")
            .join(A)
            .join(FOLDER)
            .join("index.html"),
        b"web-a",
    );
    // S3 leaves B staged with its archive.
    let staged = updates.join("staged");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staged)
        .unwrap();
    private_file(&staged.join(IMAGE), b"image-b");
    private_file(&staged.join("VERSION"), format!("{B}\n").as_bytes());
    drop(archive(
        &scratch.0.join("b.tar"),
        &[(b"index.html", tar::EntryType::Regular, b"web-b", b"")],
    ));
    private_file(
        &staged.join(ARCHIVE),
        &std::fs::read(scratch.0.join("b.tar")).unwrap(),
    );

    let switch = crate::apply::install(
        crate::update::Confirmed::for_test(B, &updates, IMAGE),
        IMAGE,
    )
    .unwrap();
    let b = updates.join("releases").join(B);
    assert_eq!(std::fs::read(b.join("web/index.html")).unwrap(), b"web-b");
    let running = std::fs::File::open(updates.join("releases").join(A).join(IMAGE)).unwrap();
    switch.save_previous(&running, IMAGE).unwrap();
    switch
        .save_previous_web(Some(&updates.join("releases").join(A).join(FOLDER)))
        .unwrap();
    assert_eq!(
        std::fs::read(updates.join("previous/web/index.html")).unwrap(),
        b"web-a"
    );
    drop(switch);
    let leftovers = std::fs::read_dir(&updates)
        .unwrap()
        .filter(|entry| {
            let name = entry.as_ref().unwrap().file_name();
            let name = name.to_string_lossy();
            name.starts_with("download-") || name.starts_with("retired-")
        })
        .count();
    assert_eq!(leftovers, 0, "no half-made folder is left");

    // B passed its trial: the commit points `current` at B and removes A's folder.
    std::fs::remove_dir_all(updates.join("releases").join(A)).unwrap();
    std::os::unix::fs::symlink(Path::new("releases").join(B), updates.join("current")).unwrap();
    let mut from = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(updates.join("previous").join(crate::apply::FROM))
        .unwrap();
    write!(
        from,
        r#"{{"version":"{A}","path":"{}"}}"#,
        updates.join("releases").join(A).join(IMAGE).display()
    )
    .unwrap();
    drop(from);
    crate::apply::begin_manual_rollback(&data, IMAGE, B, &"bb".repeat(32)).unwrap();
    assert_eq!(
        std::fs::read(updates.join("current/web/index.html")).unwrap(),
        b"web-a",
        "the previous release serves its own web build again"
    );
}
