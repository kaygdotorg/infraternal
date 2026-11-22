//! Installing a signed release by hand, so an existing server can move onto the boot pointer (#211 S6).
//!
//! A server installed before auto-update (production: an operator's unit that starts a
//! fixed `/opt/infraternal/<build>/infraternal`) has no `updates/releases/` and no
//! `current` pointer yet. `infraternal server update adopt <release folder>` moves it:
//! it calls [`install`] here to put a signed release folder (as `scripts/release/build`
//! writes it, or as it was downloaded) into `<data>/updates/releases/<version>/` and to
//! point `current` at it, then rewrites the unit to start `current/<image>` and restarts
//! the running server into the release warm. This module is only the file side; the CLI
//! (`crates/infraternal/src/server_adopt.rs`) does the unit and the restart.
//!
//! **The same rules as the updater.** Everything happens under the update folder's lock
//! ([`crate::update`]), so no check or switch runs meanwhile, and never while a switch is
//! in flight (`pending.json`). The release's files are copied into a fresh `download-*`
//! folder first and verified there with the one signed-release verifier (the image and,
//! when the signed list names it, the web build), so what is installed is exactly what
//! was verified, whatever happens to the source folder. The web build is unpacked with
//! [`crate::web::extract`]. The folder is renamed into place whole.
//!
//! **Idempotent.** An installed `releases/<version>/` whose image has the same bytes is
//! kept as it is (only `current` is pointed at it). The same version with other bytes is
//! refused: a signed release never changes, so that means something is wrong.
use crate::update::{Locked, open_private};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

/// What [`install`] installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    /// The signed release version.
    pub version: String,
    /// `<data>/updates/releases/<version>/<image>`, the path to restart into.
    pub image: PathBuf,
    /// Whether the release carries its own web build (`releases/<version>/web/`).
    pub web: bool,
    /// Whether this release folder was already installed with the same image and kept.
    pub kept: bool,
}

/// What [`install`] would do now, for a dry run: nothing is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// The signed version of the release folder.
    pub version: String,
    /// Whether the release carries a web build.
    pub web: bool,
    /// Whether `releases/<version>/` already holds this exact image.
    pub installed: bool,
    /// What `current` points at now, relative to `updates/` (for example `releases/<v>`).
    pub current: Option<PathBuf>,
}

/// The verifier [`install`] uses: (signed `VERSION`, payload, payload name, `SHA256SUMS`,
/// `SHA256SUMS.sig`) to the signed version. The server passes the compiled-in release keys.
pub type Verify<'a> = &'a dyn Fn(&File, &File, &str, &[u8], &[u8]) -> Result<String, &'static str>;

/// Verify the release folder `source` without changing anything, and say what [`install`]
/// would do in `data` (see [`Plan`]).
/// # Errors
/// The release folder is incomplete, unsigned or not this machine's, or the data folder's
/// update folder is unsafe.
pub fn plan(
    data: &Path,
    source: &Path,
    artifact: &str,
    verify: Verify<'_>,
) -> Result<Plan, &'static str> {
    let (version, web) = verify_source(source, artifact, verify)?;
    let updates = data.join("updates");
    let installed = std::fs::File::open(updates.join("releases").join(&version).join(artifact))
        .ok()
        .and_then(|file| crate::apply::digest(&file).ok())
        .zip(
            File::open(source.join(artifact))
                .ok()
                .and_then(|file| crate::apply::digest(&file).ok()),
        )
        .is_some_and(|(installed, source)| installed == source);
    Ok(Plan {
        version,
        web,
        installed,
        current: std::fs::read_link(updates.join("current")).ok(),
    })
}

/// Install the signed release folder `source` as `<data>/updates/releases/<version>/` and
/// point `current` at it (see the module docs).
///
/// `artifact` is this machine's server image name ([`crate::update::SERVER_IMAGE`], never an
/// `infraternal-<arch>-musl` add-host payload). The updates folder
/// is created (0700, owned by this account) if needed, as the updater does.
/// # Errors
/// A fixed sentence: an update check or switch holds the folder or a switch is in flight;
/// the release is incomplete, unsigned, not this machine's, or a different build under an
/// installed version; or it could not be written.
pub fn install(
    data: &Path,
    source: &Path,
    artifact: &str,
    verify: Verify<'_>,
) -> Result<Installed, &'static str> {
    let updates = data.join("updates");
    let lock = Locked::try_open(&updates).map_err(
        |_| "an update check or switch is using the update folder; try again in a minute",
    )?;
    if crate::apply::in_flight(data) {
        return Err("an update switch has not finished; wait for it, then try again");
    }
    lock.sweep()?;
    let mut folder = lock.download()?;
    let mut names = vec![
        ("SHA256SUMS", 65_536),
        ("SHA256SUMS.sig", 1024),
        ("VERSION", 128),
    ];
    names.push((artifact, crate::update::MAX_IMAGE));
    for (name, limit) in &names {
        copy(
            &source.join(name),
            &folder.path.join(name),
            *limit,
            *name == artifact,
        )?;
    }
    let sums = read(&folder.path.join("SHA256SUMS"), 65_536)?;
    let web = crate::web::listed(&sums);
    if web {
        copy(
            &source.join(crate::web::ARCHIVE),
            &folder.path.join(crate::web::ARCHIVE),
            crate::web::MAX_ARCHIVE,
            false,
        )?;
    }
    let (version, image) = verify_folder(&folder.path, artifact, web, verify)?;
    let releases = updates.join("releases");
    make_private(&releases)?;
    let target = releases.join(&version);
    let kept = match File::open(target.join(artifact)) {
        Ok(existing) => {
            if crate::apply::digest(&existing)? != crate::apply::digest(&image)? {
                return Err(
                    "this version is already installed with a different image; a signed release never changes, so check where this folder came from",
                );
            }
            true
        }
        Err(_) => false,
    };
    if !kept {
        if web {
            let archive = open_private(&folder.path.join(crate::web::ARCHIVE))?;
            crate::web::extract(&archive, &folder.path.join(crate::web::FOLDER))?;
        }
        if std::fs::symlink_metadata(&target).is_ok() {
            // A partial folder from an interrupted install: replace it whole.
            let retired = updates.join(format!("retired-{}", uuid::Uuid::new_v4().hyphenated()));
            std::fs::rename(&target, &retired)
                .map_err(|_| "an old release could not be removed")?;
            std::fs::remove_dir_all(&retired).map_err(|_| "an old release could not be removed")?;
        }
        std::fs::rename(&folder.path, &target).map_err(|_| "the release could not be installed")?;
        folder.published = true;
        sync(&releases)?;
    }
    crate::apply::point_current(&lock, &version)?;
    Ok(Installed {
        image: target.join(artifact),
        web: web || target.join(crate::web::FOLDER).is_dir(),
        version,
        kept,
    })
}

/// Verify `source` in place (read-only) and return its signed version and whether it has a
/// web build. Used by the dry run; [`install`] verifies its own private copies instead.
fn verify_source(
    source: &Path,
    artifact: &str,
    verify: Verify<'_>,
) -> Result<(String, bool), &'static str> {
    let sums = read(&source.join("SHA256SUMS"), 65_536)?;
    let web = crate::web::listed(&sums);
    let signature = read(&source.join("SHA256SUMS.sig"), 1024)?;
    let version = public(&source.join("VERSION"))?;
    let image = public(&source.join(artifact))?;
    let signed = verify(&version, &image, artifact, &sums, &signature)?;
    if web {
        let archive = public(&source.join(crate::web::ARCHIVE))?;
        verify(&version, &archive, crate::web::ARCHIVE, &sums, &signature)?;
    }
    Ok((signed, web))
}

/// Verify the private copies in `folder` and return the signed version and the open image.
fn verify_folder(
    folder: &Path,
    artifact: &str,
    web: bool,
    verify: Verify<'_>,
) -> Result<(String, File), &'static str> {
    let sums = read(&folder.join("SHA256SUMS"), 65_536)?;
    let signature = read(&folder.join("SHA256SUMS.sig"), 1024)?;
    let version = open_private(&folder.join("VERSION"))?;
    let image = open_private(&folder.join(artifact))?;
    let signed = verify(&version, &image, artifact, &sums, &signature)?;
    if web {
        let archive = open_private(&folder.join(crate::web::ARCHIVE))?;
        verify(&version, &archive, crate::web::ARCHIVE, &sums, &signature)?;
    }
    Ok((signed, image))
}

/// Open a release file read-only without following a final link; it must be a regular file.
fn public(path: &Path) -> Result<File, &'static str> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "the release folder is incomplete")?;
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err("the release folder holds something that is not a file");
    }
    Ok(file)
}

/// Read at most `limit` bytes of the release file `path`; more is refused.
fn read(path: &Path, limit: u64) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    public(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "the release folder could not be read")?;
    if bytes.len() as u64 > limit {
        return Err("a release file is oversized");
    }
    Ok(bytes)
}

/// Copy the release file `from` (at most `limit` bytes) into the new private file `to`
/// (0700 for the image, 0600 otherwise), flushed.
fn copy(from: &Path, to: &Path, limit: u64, executable: bool) -> Result<(), &'static str> {
    let saved = "the release could not be copied";
    let source = public(from)?;
    if source.metadata().map_err(|_| saved)?.len() > limit {
        return Err("a release file is oversized");
    }
    let mut target = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(if executable { 0o700 } else { 0o600 })
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(to)
        .map_err(|_| saved)?;
    let copied = std::io::copy(&mut source.take(limit + 1), &mut target).map_err(|_| saved)?;
    if copied > limit {
        return Err("a release file is oversized");
    }
    target
        .flush()
        .and_then(|()| target.sync_all())
        .map_err(|_| saved)
}

/// Create `path` as a private folder if it is missing; an existing one must be a real
/// folder owned by this account with no group or other access.
#[allow(clippy::verbose_bit_mask)]
fn make_private(path: &Path) -> Result<(), &'static str> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata =
                std::fs::symlink_metadata(path).map_err(|_| "the update folder is unsafe")?;
            (metadata.is_dir()
                && metadata.uid() == nix::unistd::geteuid().as_raw()
                && metadata.mode() & 0o077 == 0)
                .then_some(())
                .ok_or("the update folder is unsafe")
        }
        Err(_) => Err("the update folder is unavailable"),
    }
}

/// Flush the folder `path` so the rename inside it survives a crash.
fn sync(path: &Path) -> Result<(), &'static str> {
    File::open(path)
        .and_then(|folder| folder.sync_all())
        .map_err(|_| "the release could not be saved")
}

/// Unit checks for installing a release folder by hand.
#[cfg(test)]
#[path = "adopt_tests.rs"]
mod tests;
