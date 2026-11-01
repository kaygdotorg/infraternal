//! Publishes only signed, bounded Traefik executables into the node-local component store [#281].

use crate::manifest::{
    ComponentManifestVerifier, MAX_COMPONENT_ARCHIVE_BYTES, MAX_COMPONENT_EXECUTABLE_BYTES,
    VerifiedComponentManifest, verify_component_manifest,
};
use nix::fcntl::{Flock, FlockArg};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const EXECUTABLE_MODE: u32 = 0o500;
const MAX_ARCHIVE_ENTRIES: usize = 256;
const MAX_LICENSE_BYTES: u64 = 1024 * 1024;
const MAX_EXPANDED_ARCHIVE_BYTES: u64 =
    MAX_COMPONENT_EXECUTABLE_BYTES + MAX_LICENSE_BYTES + 2 * 1024 * 1024;

/// Owns the downloaded-on-demand component directory beneath one infraternal state directory.
pub struct ComponentInstaller {
    state: PathBuf,
}

/// The signed metadata files that accompany an offline component archive.
#[derive(Clone, Copy)]
pub struct SignedComponentBundle<'a> {
    /// Component manifest bytes included in the release bundle.
    pub manifest: &'a [u8],
    /// Signed checksum-list basename that names the component manifest.
    pub manifest_filename: &'a str,
    /// Existing product release checksum list covering the component manifest.
    pub signed_checksums: &'a [u8],
    /// Existing product release signature over `signed_checksums`.
    pub signature: &'a [u8],
}

impl ComponentInstaller {
    /// Bind installation to the agent's state directory; permissions are checked on each install.
    #[must_use]
    pub fn new(state: &Path) -> Self {
        Self {
            state: state.to_owned(),
        }
    }

    /// Verify an archive against a release-signed manifest, then atomically publish its executable.
    ///
    /// The archive is first streamed into an exclusive private temporary file and hashed before any
    /// decompression. Extraction accepts only the two signed release members and writes the single
    /// executable into a private staging directory before an atomic directory rename.
    ///
    /// # Errors
    /// Returns an error when the signed target, archive, extracted files or store permissions fail validation.
    pub fn install_archive<R: Read>(
        &self,
        manifest: &VerifiedComponentManifest,
        archive: R,
        os: &str,
        arch: &str,
    ) -> io::Result<PathBuf> {
        manifest.manifest().validate_for(os, arch)?;
        let root = self.store_directory()?;
        let _lock = lock_store(&root)?;
        let archive_file = stage_archive(&root, manifest, archive)?;
        let digest = &manifest.manifest().executable_sha256;
        let destination = root.join(digest);
        if path_exists(&destination)? {
            validate_installed(&destination, manifest)?;
            return Ok(destination.join("bin").join("traefik"));
        }

        let mut staging = TemporaryDirectory::create(&root)?;
        let bin = staging.path.join("bin");
        create_private_directory(&bin)?;
        extract_executable(&archive_file.path, &bin, manifest)?;
        sync_directory(&bin)?;
        sync_directory(&staging.path)?;
        fs::rename(&staging.path, &destination)?;
        staging.disarm();
        sync_directory(&root)?;
        Ok(destination.join("bin").join("traefik"))
    }

    /// Install bytes streamed directly from an authenticated component source.
    ///
    /// # Errors
    /// Returns an error when source streaming, digest validation, extraction or store permissions fail.
    pub fn install_stream<F>(
        &self,
        _manifest: &VerifiedComponentManifest,
        _download: F,
        _os: &str,
        _arch: &str,
    ) -> io::Result<PathBuf>
    where
        F: FnOnce(&mut dyn Write) -> io::Result<()>,
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "stream installation is not implemented",
        ))
    }

    /// Import the offline bundle using the same signed manifest and archive verification path.
    ///
    /// # Errors
    /// Returns an error when signed metadata, the archive, extracted files or store permissions are invalid.
    pub fn import_bundle<R: Read>(
        &self,
        bundle: SignedComponentBundle<'_>,
        os: &str,
        arch: &str,
        verifier: &dyn ComponentManifestVerifier,
        archive: R,
    ) -> io::Result<PathBuf> {
        let manifest = verify_component_manifest(
            bundle.manifest,
            bundle.manifest_filename,
            bundle.signed_checksums,
            bundle.signature,
            os,
            arch,
            verifier,
        )?;
        self.install_archive(&manifest, archive, os, arch)
    }

    fn store_directory(&self) -> io::Result<PathBuf> {
        validate_directory(&self.state, PRIVATE_DIRECTORY_MODE)?;
        let components = self.state.join("components");
        create_private_directory(&components)?;
        let proxy = components.join("proxy");
        create_private_directory(&proxy)?;
        Ok(proxy)
    }
}

fn stage_archive<R: Read>(
    root: &Path,
    verified: &VerifiedComponentManifest,
    mut source: R,
) -> io::Result<TemporaryFile> {
    let manifest = verified.manifest();
    if manifest.archive_size == 0 || manifest.archive_size > MAX_COMPONENT_ARCHIVE_BYTES {
        return Err(invalid_data("component archive exceeds its byte limit"));
    }
    let temporary = TemporaryFile::create(root, ".archive-")?;
    let mut output = OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&temporary.path)?;
    let mut digest = Sha256::new();
    let mut received = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        received = received
            .checked_add(u64::try_from(count).map_err(|_| invalid_data("archive is too large"))?)
            .ok_or_else(|| invalid_data("archive is too large"))?;
        if received > manifest.archive_size || received > MAX_COMPONENT_ARCHIVE_BYTES {
            return Err(invalid_data("component archive exceeds its declared size"));
        }
        output.write_all(&buffer[..count])?;
        digest.update(&buffer[..count]);
    }
    if received != manifest.archive_size
        || format!("{:x}", digest.finalize()) != manifest.archive_sha256
    {
        return Err(invalid_data(
            "component archive does not match its signed digest",
        ));
    }
    output.sync_all()?;
    validate_file_metadata(&output.metadata()?, PRIVATE_FILE_MODE)?;
    Ok(temporary)
}

fn extract_executable(
    archive_path: &Path,
    bin: &Path,
    verified: &VerifiedComponentManifest,
) -> io::Result<()> {
    let manifest = verified.manifest();
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(archive_path)?;
    let decoder = flate2::read::GzDecoder::new(input);
    let limited = decoder.take(MAX_EXPANDED_ARCHIVE_BYTES + 1);
    let mut archive = tar::Archive::new(limited);
    let mut executable_found = false;
    let mut license_found = false;
    let mut entry_count = 0_usize;

    for entry in archive.entries()? {
        let mut entry = entry?;
        entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| invalid_data("component archive has too many entries"))?;
        if entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(invalid_data("component archive has too many entries"));
        }
        let raw_path = entry.path_bytes();
        let path = raw_path.as_ref();
        let entry_type = entry.header().entry_type();
        let mode = entry.header().mode()?;
        if !entry_type.is_file() || mode & 0o6000 != 0 {
            return Err(invalid_data(
                "component archive contains a non-regular entry",
            ));
        }
        if path == b"traefik" && !executable_found {
            if entry.size() != manifest.executable_size
                || entry.size() == 0
                || entry.size() > MAX_COMPONENT_EXECUTABLE_BYTES
            {
                return Err(invalid_data(
                    "Traefik executable size does not match its manifest",
                ));
            }
            let destination = bin.join("traefik");
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(PRIVATE_FILE_MODE)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                .open(&destination)?;
            let mut digest = Sha256::new();
            let mut written = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let count = entry.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                written = written
                    .checked_add(
                        u64::try_from(count)
                            .map_err(|_| invalid_data("executable is too large"))?,
                    )
                    .ok_or_else(|| invalid_data("executable is too large"))?;
                if written > manifest.executable_size {
                    return Err(invalid_data("Traefik executable exceeds its declared size"));
                }
                output.write_all(&buffer[..count])?;
                digest.update(&buffer[..count]);
            }
            if written != manifest.executable_size
                || format!("{:x}", digest.finalize()) != manifest.executable_sha256
            {
                return Err(invalid_data(
                    "Traefik executable does not match its signed digest",
                ));
            }
            output.set_permissions(fs::Permissions::from_mode(EXECUTABLE_MODE))?;
            output.sync_all()?;
            validate_file_metadata(&output.metadata()?, EXECUTABLE_MODE)?;
            if hash_file(&destination)? != manifest.executable_sha256 {
                return Err(invalid_data(
                    "installed Traefik executable failed its digest check",
                ));
            }
            executable_found = true;
        } else if path == b"LICENSE.md" && !license_found {
            let declared_size = entry.size();
            if declared_size == 0 || declared_size > MAX_LICENSE_BYTES {
                return Err(invalid_data("Traefik license file exceeds its byte limit"));
            }
            let mut bytes = Vec::with_capacity(
                usize::try_from(declared_size).map_err(|_| invalid_data("license is too large"))?,
            );
            entry.take(declared_size + 1).read_to_end(&mut bytes)?;
            if u64::try_from(bytes.len()).map_err(|_| invalid_data("license is too large"))?
                != declared_size
                || !bytes.windows(11).any(|part| part == b"MIT License")
            {
                return Err(invalid_data(
                    "Traefik archive does not contain its MIT license",
                ));
            }
            license_found = true;
        } else {
            return Err(invalid_data(
                "component archive contains an unallowlisted path",
            ));
        }
    }

    if !executable_found || !license_found {
        return Err(invalid_data(
            "component archive is missing a required member",
        ));
    }
    let mut remaining = archive.into_inner();
    io::copy(&mut remaining, &mut io::sink())?;
    if remaining.limit() == 0 {
        return Err(invalid_data(
            "component archive expands beyond its byte limit",
        ));
    }
    Ok(())
}

fn validate_installed(directory: &Path, verified: &VerifiedComponentManifest) -> io::Result<()> {
    validate_directory(directory, PRIVATE_DIRECTORY_MODE)?;
    let bin = directory.join("bin");
    validate_directory(&bin, PRIVATE_DIRECTORY_MODE)?;
    let executable = bin.join("traefik");
    let metadata = fs::symlink_metadata(&executable)?;
    validate_file_metadata(&metadata, EXECUTABLE_MODE)?;
    if metadata.len() != verified.manifest().executable_size
        || hash_file(&executable)? != verified.manifest().executable_sha256
        || fs::read_dir(&bin)?.count() != 1
    {
        return Err(invalid_data(
            "existing component installation is inconsistent",
        ));
    }
    Ok(())
}

fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn lock_store(root: &Path) -> io::Result<Flock<File>> {
    let path = root.join(".install.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    validate_file_metadata(&lock.metadata()?, PRIVATE_FILE_MODE)?;
    Flock::lock(lock, FlockArg::LockExclusive).map_err(|(_, error)| io::Error::from(error))
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => return validate_directory(path, PRIVATE_DIRECTORY_MODE),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error),
    }
    validate_directory(path, PRIVATE_DIRECTORY_MODE)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn validate_directory(path: &Path, expected_mode: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o7777 != expected_mode
    {
        return Err(permission_error(
            "component directory has unsafe owner or mode",
        ));
    }
    Ok(())
}

fn validate_file_metadata(metadata: &fs::Metadata, expected_mode: u32) -> io::Result<()> {
    if !metadata.file_type().is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o7777 != expected_mode
        || metadata.nlink() != 1
    {
        return Err(permission_error(
            "component file has unsafe owner, mode, or links",
        ));
    }
    Ok(())
}

fn path_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn permission_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

struct TemporaryFile {
    path: PathBuf,
    armed: bool,
}

impl TemporaryFile {
    fn create(parent: &Path, prefix: &str) -> io::Result<Self> {
        let path = parent.join(format!("{prefix}{}.tmp", uuid::Uuid::new_v4()));
        let _file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&path)?;
        Ok(Self { path, armed: true })
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct TemporaryDirectory {
    path: PathBuf,
    armed: bool,
}

impl TemporaryDirectory {
    fn create(parent: &Path) -> io::Result<Self> {
        let path = parent.join(format!(".install-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))?;
        validate_directory(&path, PRIVATE_DIRECTORY_MODE)?;
        Ok(Self { path, armed: true })
    }

    fn disarm(&mut self) {
        // The successful rename moved this path to the content-addressed destination.
        // `Drop` only needs to stop cleaning up the path that no longer exists.
        self.armed = false;
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
