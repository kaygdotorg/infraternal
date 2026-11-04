//! Publishes only signed, bounded Traefik executables into the node-local component store [#281].

use crate::identity;
use crate::manifest::{
    ComponentManifest, ComponentManifestVerifier, MAX_COMPONENT_ARCHIVE_BYTES,
    MAX_COMPONENT_EXECUTABLE_BYTES, MAX_RELEASE_SIGNATURE_BYTES, MAX_SIGNED_RELEASE_METADATA_BYTES,
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
const ROOTFUL_EXECUTABLE_MODE: u32 = 0o550;
const ROOTLESS_EXECUTABLE_MODE: u32 = 0o500;
const LEGACY_ROOTFUL_EXECUTABLE_MODE: u32 = 0o500;
const MAX_ARCHIVE_ENTRIES: usize = 256;
const MAX_LICENSE_BYTES: u64 = 1024 * 1024;
const MAX_CHANGELOG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_EXPANDED_ARCHIVE_BYTES: u64 =
    MAX_COMPONENT_EXECUTABLE_BYTES + MAX_LICENSE_BYTES + MAX_CHANGELOG_BYTES + 2 * 1024 * 1024;

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
    /// decompression. Extraction accepts the signed executable, license, and bounded changelog
    /// members, writing only the executable into a private staging directory before atomic rename.
    ///
    /// # Errors
    /// Returns an error when the signed target, archive, extracted files or store permissions fail validation.
    pub fn install_archive<R: Read>(
        &self,
        manifest: &VerifiedComponentManifest,
        mut archive: R,
        os: &str,
        arch: &str,
    ) -> io::Result<PathBuf> {
        self.install_stream(
            manifest,
            |output| io::copy(&mut archive, output).map(|_| ()),
            os,
            arch,
        )
    }

    /// Install bytes streamed directly from an authenticated component source.
    ///
    /// # Errors
    /// Returns an error when source streaming, digest validation, extraction or store permissions fail.
    pub fn install_stream<F>(
        &self,
        manifest: &VerifiedComponentManifest,
        download: F,
        os: &str,
        arch: &str,
    ) -> io::Result<PathBuf>
    where
        F: FnOnce(&mut dyn Write) -> io::Result<()>,
    {
        manifest.manifest().validate_for(os, arch)?;
        let root = self.store_directory()?;
        let _lock = lock_store(&root)?;
        let destination = root.join(&manifest.manifest().executable_sha256);
        if path_exists(&destination)? {
            validate_installed(&destination, manifest)?;
            store_signed_bundle(&destination, manifest)?;
            return Ok(destination.join("bin").join("traefik"));
        }

        let archive_file = stage_archive(&root, manifest, download)?;
        let mut staging = TemporaryDirectory::create(&root)?;
        let bin = staging.path.join("bin");
        create_private_directory(&bin)?;
        extract_executable(&archive_file.path, &bin, manifest)?;
        store_signed_bundle(&staging.path, manifest)?;
        sync_directory(&bin)?;
        sync_directory(&staging.path)?;
        fs::rename(&staging.path, &destination)?;
        staging.disarm();
        sync_directory(&root)?;
        Ok(destination.join("bin").join("traefik"))
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

    /// Reuse a locally installed executable only when its persisted release signature still verifies.
    ///
    /// # Errors
    /// Returns an error when a candidate bundle is malformed, untrusted, or its executable was changed.
    pub(crate) fn find_installed(
        &self,
        release_version: &str,
        os: &str,
        arch: &str,
        verifier: &dyn ComponentManifestVerifier,
    ) -> io::Result<Option<PathBuf>> {
        if !crate::manifest::valid_release_version(release_version)
            || !matches!(os, "linux" | "darwin")
            || !matches!(arch, "amd64" | "arm64")
        {
            return Err(invalid_data("component lookup target is invalid"));
        }
        // A read-only lookup must not create the component tree before the remote manifest is trusted.
        let Some(root) = self.existing_store_directory()? else {
            return Ok(None);
        };
        let _lock = lock_store(&root)?;
        let manifest_filename = ComponentManifest::signed_filename(os, arch);
        let mut found = None;
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(digest) = name.to_str() else {
                continue;
            };
            if !valid_component_digest(digest) {
                continue;
            }
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let directory = entry.path();
            validate_directory(&directory, PRIVATE_DIRECTORY_MODE)?;
            let bundles = directory.join("bundles");
            let release = bundles.join(release_version);
            let target = release.join(os).join(arch);
            if !path_exists(&target)? {
                continue;
            }
            validate_directory(&bundles, PRIVATE_DIRECTORY_MODE)?;
            validate_directory(&release, PRIVATE_DIRECTORY_MODE)?;
            validate_directory(&release.join(os), PRIVATE_DIRECTORY_MODE)?;
            validate_directory(&target, PRIVATE_DIRECTORY_MODE)?;

            let manifest_bytes = read_signed_metadata(
                &target.join(&manifest_filename),
                MAX_SIGNED_RELEASE_METADATA_BYTES,
            )?;
            let checksums = read_signed_metadata(
                &target.join("SHA256SUMS"),
                MAX_SIGNED_RELEASE_METADATA_BYTES,
            )?;
            let signature =
                read_signed_metadata(&target.join("SHA256SUMS.sig"), MAX_RELEASE_SIGNATURE_BYTES)?;
            let candidate = verify_component_manifest(
                &manifest_bytes,
                &manifest_filename,
                &checksums,
                &signature,
                os,
                arch,
                verifier,
            )?;
            if candidate.manifest().release_version != release_version
                || candidate.manifest().executable_sha256 != digest
            {
                return Err(invalid_data(
                    "stored component bundle does not match its installation path",
                ));
            }
            validate_installed(&directory, &candidate)?;
            if found.is_some() {
                return Err(invalid_data(
                    "multiple installed components match the requested release",
                ));
            }
            found = Some(directory.join("bin").join("traefik"));
        }
        Ok(found)
    }

    fn store_directory(&self) -> io::Result<PathBuf> {
        validate_directory(&self.state, PRIVATE_DIRECTORY_MODE)?;
        let components = self.state.join("components");
        create_private_directory(&components)?;
        let proxy = components.join("proxy");
        create_private_directory(&proxy)?;
        Ok(proxy)
    }

    fn existing_store_directory(&self) -> io::Result<Option<PathBuf>> {
        validate_directory(&self.state, PRIVATE_DIRECTORY_MODE)?;
        let components = self.state.join("components");
        match fs::symlink_metadata(&components) {
            Ok(_) => validate_directory(&components, PRIVATE_DIRECTORY_MODE)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        }
        let proxy = components.join("proxy");
        match fs::symlink_metadata(&proxy) {
            Ok(_) => validate_directory(&proxy, PRIVATE_DIRECTORY_MODE)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        }
        Ok(Some(proxy))
    }
}

fn store_signed_bundle(
    component_directory: &Path,
    verified: &VerifiedComponentManifest,
) -> io::Result<()> {
    let manifest = verified.manifest();
    let bundles = component_directory.join("bundles");
    create_private_directory(&bundles)?;
    let release = bundles.join(&manifest.release_version);
    create_private_directory(&release)?;
    let os = release.join(&manifest.os);
    create_private_directory(&os)?;
    let (manifest_bytes, manifest_filename, checksums, signature) = verified.signed_bundle_parts();
    let destination = os.join(&manifest.arch);
    if path_exists(&destination)? {
        validate_directory(&destination, PRIVATE_DIRECTORY_MODE)?;
        for (name, expected, limit) in [
            (
                manifest_filename,
                manifest_bytes,
                MAX_SIGNED_RELEASE_METADATA_BYTES,
            ),
            ("SHA256SUMS", checksums, MAX_SIGNED_RELEASE_METADATA_BYTES),
            ("SHA256SUMS.sig", signature, MAX_RELEASE_SIGNATURE_BYTES),
        ] {
            if read_signed_metadata(&destination.join(name), limit)? != expected {
                return Err(invalid_data(
                    "stored component bundle conflicts with verified release metadata",
                ));
            }
        }
        return Ok(());
    }

    let mut staging = TemporaryDirectory::create(&os)?;
    for (name, bytes) in [
        (manifest_filename, manifest_bytes),
        ("SHA256SUMS", checksums),
        ("SHA256SUMS.sig", signature),
    ] {
        write_signed_metadata(&staging.path.join(name), bytes)?;
    }
    sync_directory(&staging.path)?;
    fs::rename(&staging.path, &destination)?;
    staging.disarm();
    sync_directory(&os)?;
    Ok(())
}

fn write_signed_metadata(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    validate_file_metadata(&file.metadata()?, PRIVATE_FILE_MODE)
}

fn read_signed_metadata(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    validate_file_metadata(&file.metadata()?, PRIVATE_FILE_MODE)?;
    if file.metadata()?.len() > u64::try_from(limit).unwrap_or(u64::MAX) {
        return Err(invalid_data(
            "stored component metadata exceeds its byte limit",
        ));
    }
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid_data(
            "stored component metadata exceeds its byte limit",
        ));
    }
    Ok(bytes)
}

pub(crate) fn valid_component_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn stage_archive<F>(
    root: &Path,
    verified: &VerifiedComponentManifest,
    write_source: F,
) -> io::Result<TemporaryFile>
where
    F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
    let manifest = verified.manifest();
    if manifest.archive_size == 0 || manifest.archive_size > MAX_COMPONENT_ARCHIVE_BYTES {
        return Err(invalid_data("component archive exceeds its byte limit"));
    }
    let (temporary, mut output) = TemporaryFile::create(root, ".archive-")?;
    output.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    let mut writer = ArchiveStreamWriter {
        output: &mut output,
        expected_size: manifest.archive_size,
        expected_digest: &manifest.archive_sha256,
        received: 0,
        digest: Sha256::new(),
    };
    write_source(&mut writer)?;
    writer.finish()?;
    output.sync_all()?;
    validate_file_metadata(&output.metadata()?, PRIVATE_FILE_MODE)?;
    Ok(temporary)
}

struct ArchiveStreamWriter<'a> {
    output: &'a mut File,
    expected_size: u64,
    expected_digest: &'a str,
    received: u64,
    digest: Sha256,
}

impl ArchiveStreamWriter<'_> {
    fn finish(self) -> io::Result<()> {
        if self.received != self.expected_size
            || format!("{:x}", self.digest.finalize()) != self.expected_digest
        {
            return Err(invalid_data(
                "component archive does not match its signed length and digest",
            ));
        }
        Ok(())
    }
}

impl Write for ArchiveStreamWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let next = self
            .received
            .checked_add(
                u64::try_from(bytes.len()).map_err(|_| invalid_data("archive is too large"))?,
            )
            .ok_or_else(|| invalid_data("archive is too large"))?;
        if next > self.expected_size || next > MAX_COMPONENT_ARCHIVE_BYTES {
            return Err(invalid_data(
                "component archive exceeds its signed byte limit",
            ));
        }
        let written = self.output.write(bytes)?;
        self.received = self
            .received
            .checked_add(u64::try_from(written).map_err(|_| invalid_data("archive is too large"))?)
            .ok_or_else(|| invalid_data("archive is too large"))?;
        self.digest.update(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

fn extract_executable(
    archive_path: &Path,
    bin: &Path,
    verified: &VerifiedComponentManifest,
) -> io::Result<()> {
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(archive_path)?;
    let decoder = flate2::read::GzDecoder::new(input);
    let limited = decoder.take(MAX_EXPANDED_ARCHIVE_BYTES + 1);
    let mut archive = tar::Archive::new(limited);
    let mut members = ArchiveMembers::default();
    let mut entry_count = 0_usize;

    for entry in archive.entries()? {
        let entry = entry?;
        entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| invalid_data("component archive has too many entries"))?;
        if entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(invalid_data("component archive has too many entries"));
        }
        extract_archive_entry(entry, bin, verified.manifest(), &mut members)?;
    }

    if !members.executable || !members.license {
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

#[derive(Default)]
struct ArchiveMembers {
    executable: bool,
    license: bool,
    changelog: bool,
}

fn extract_archive_entry<R: Read>(
    entry: tar::Entry<'_, R>,
    bin: &Path,
    manifest: &ComponentManifest,
    members: &mut ArchiveMembers,
) -> io::Result<()> {
    let raw_path = entry.path_bytes();
    let path = raw_path.as_ref();
    let entry_type = entry.header().entry_type();
    let mode = entry.header().mode()?;
    if !entry_type.is_file() || mode & 0o6000 != 0 {
        return Err(invalid_data(
            "component archive contains a non-regular entry",
        ));
    }

    if path == b"traefik" && !members.executable {
        extract_allowlisted_executable(entry, bin, manifest)?;
        members.executable = true;
    } else if path == b"LICENSE.md" && !members.license {
        validate_traefik_license(entry)?;
        members.license = true;
    } else if path == b"CHANGELOG.md" && !members.changelog {
        validate_traefik_changelog(entry)?;
        members.changelog = true;
    } else {
        return Err(invalid_data(
            "component archive contains an unallowlisted path",
        ));
    }
    Ok(())
}

fn extract_allowlisted_executable<R: Read>(
    mut entry: tar::Entry<'_, R>,
    bin: &Path,
    manifest: &ComponentManifest,
) -> io::Result<()> {
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
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = entry.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        written = written
            .checked_add(u64::try_from(count).map_err(|_| invalid_data("executable is too large"))?)
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
    if identity::rootful() {
        nix::unistd::fchown(
            &output,
            Some(nix::unistd::Uid::effective()),
            Some(nix::unistd::Gid::from_raw(identity::child_group()?)),
        )?;
    }
    output.set_permissions(fs::Permissions::from_mode(executable_mode()))?;
    output.sync_all()?;
    validate_executable_metadata(&output.metadata()?)?;
    if hash_file(&destination)? != manifest.executable_sha256 {
        return Err(invalid_data(
            "installed Traefik executable failed its digest check",
        ));
    }
    Ok(())
}

fn validate_traefik_license<R: Read>(entry: tar::Entry<'_, R>) -> io::Result<()> {
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
    Ok(())
}

fn validate_traefik_changelog<R: Read>(entry: tar::Entry<'_, R>) -> io::Result<()> {
    let declared_size = entry.size();
    if declared_size > MAX_CHANGELOG_BYTES {
        return Err(invalid_data("Traefik changelog exceeds its byte limit"));
    }
    let read_size = io::copy(&mut entry.take(MAX_CHANGELOG_BYTES + 1), &mut io::sink())?;
    if read_size != declared_size {
        return Err(invalid_data(
            "Traefik changelog does not match its declared size",
        ));
    }
    Ok(())
}

fn validate_installed(directory: &Path, verified: &VerifiedComponentManifest) -> io::Result<()> {
    validate_directory(directory, PRIVATE_DIRECTORY_MODE)?;
    let bin = directory.join("bin");
    validate_directory(&bin, PRIVATE_DIRECTORY_MODE)?;
    let executable = bin.join("traefik");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&executable)?;
    let metadata = file.metadata()?;
    if metadata.len() != verified.manifest().executable_size
        || hash_file(&executable)? != verified.manifest().executable_sha256
        || fs::read_dir(&bin)?.count() != 1
    {
        return Err(invalid_data(
            "existing component installation is inconsistent",
        ));
    }
    if validate_executable_metadata(&metadata).is_err() {
        if !identity::rootful()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.gid() != nix::unistd::Gid::effective().as_raw()
            || metadata.mode() & 0o7777 != LEGACY_ROOTFUL_EXECUTABLE_MODE
            || !metadata.file_type().is_file()
            || metadata.nlink() != 1
        {
            return Err(permission_error(
                "installed proxy executable has unsafe owner or mode",
            ));
        }
        nix::unistd::fchown(
            &file,
            Some(nix::unistd::Uid::effective()),
            Some(nix::unistd::Gid::from_raw(identity::child_group()?)),
        )?;
        file.set_permissions(fs::Permissions::from_mode(ROOTFUL_EXECUTABLE_MODE))?;
        file.sync_all()?;
        validate_executable_metadata(&file.metadata()?)?;
    }
    let path_metadata = fs::symlink_metadata(&executable)?;
    if path_metadata.dev() != metadata.dev() || path_metadata.ino() != metadata.ino() {
        return Err(permission_error(
            "installed proxy executable changed during validation",
        ));
    }
    Ok(())
}

fn executable_mode() -> u32 {
    if identity::rootful() {
        ROOTFUL_EXECUTABLE_MODE
    } else {
        ROOTLESS_EXECUTABLE_MODE
    }
}

fn validate_executable_metadata(metadata: &fs::Metadata) -> io::Result<()> {
    let expected_gid = if identity::rootful() {
        identity::child_group()?
    } else {
        nix::unistd::Gid::effective().as_raw()
    };
    if !metadata.file_type().is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o7777 != executable_mode()
        || metadata.nlink() != 1
    {
        return Err(permission_error(
            "proxy executable has unsafe owner or mode",
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
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
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
    lock.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
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
    fn create(parent: &Path, prefix: &str) -> io::Result<(Self, File)> {
        let path = parent.join(format!("{prefix}{}.tmp", uuid::Uuid::new_v4()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&path)?;
        Ok((Self { path, armed: true }, file))
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
